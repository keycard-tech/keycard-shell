#include "stm32_internal.h"

const hal_flash_data_segment_t hal_flash_data_map[] = {
    { .addr = HAL_FLASH_BLOCK_ADDR(80), .count = 48},
    { .addr = HAL_FLASH_BLOCK_ADDR(208), .count = 48},
};

const hal_flash_data_segment_t hal_flash_data_map_swap[] = {
    { .addr = HAL_FLASH_BLOCK_ADDR(208), .count = 48},
    { .addr = HAL_FLASH_BLOCK_ADDR(80), .count = 48},
};

const hal_flash_data_segment_t* hal_flash_get_data_segments() {
  return FLASH_BANK_SWAPPED() ? hal_flash_data_map_swap : hal_flash_data_map ;
}

hal_err_t hal_flash_begin_program() {
  return HAL_FLASH_Unlock();
}

hal_err_t hal_flash_wait_program() {
  HAL_WAIT(hal_flash_busy());
  return HAL_SUCCESS;
}

hal_err_t hal_flash_program(const uint8_t* data, uint8_t* addr, size_t len) {
  size_t write_len = (16 - (((uint32_t) addr) & 0xf)) & 0xf;

  hal_err_t err = HAL_SUCCESS;

  if (!write_len) {
    SET_BIT(FLASH_NS->NSCR, FLASH_CR_PG);
  } else {
    memcpy(addr, data, write_len);
    err = hal_flash_wait_program();

    data += write_len;
    addr += write_len;
    len -= write_len;
  }

  write_len = (len & ~0xf);

  if (write_len) {
    memcpy(addr, data, write_len);
    err = hal_flash_wait_program();

    data += write_len;
    addr += write_len;
    len -= write_len;
  }

  if (!len) {
    CLEAR_BIT(FLASH_NS->NSCR, FLASH_CR_PG);
  } else {
    memcpy(addr, data, len);
  }

  return err;
}

hal_err_t hal_flash_erase(uint32_t block) {
  FLASH_EraseInitTypeDef op;
  op.TypeErase = FLASH_TYPEERASE_SECTORS;
  op.NbSectors = 1;
  op.Sector = block;

  if (op.Sector >= FLASH_SECTOR_NB) {
    op.Sector -= FLASH_SECTOR_NB;
    op.Banks = FLASH_BANK_SWAPPED() ? FLASH_BANK_1 : FLASH_BANK_2;
  } else {
    op.Banks = FLASH_BANK_SWAPPED() ? FLASH_BANK_2 : FLASH_BANK_1;
  }

  uint32_t err;
  return HAL_FLASHEx_Erase(&op, &err);
}

hal_err_t hal_flash_end_program() {
  HAL_ICACHE_Invalidate();
  CLEAR_BIT(FLASH_NS->NSCR, FLASH_CR_PG);
  return HAL_FLASH_Lock();
}

void hal_flash_switch_firmware() {
  HAL_FLASH_OB_Unlock();
  FLASH_OBProgramInitTypeDef ob;
  memset(&ob, 0, sizeof(ob));
  HAL_FLASHEx_OBGetConfig(&ob);
  ob.OptionType = OPTIONBYTE_USER;
  ob.USERType = OB_USER_SWAP_BANK;
  ob.USERConfig = (ob.USERConfig & (~FLASH_OPTSR_SWAP_BANK)) | ((~ob.USERConfig) & FLASH_OPTSR_SWAP_BANK);
  HAL_FLASHEx_OBProgram(&ob);
  HAL_FLASH_OB_Launch();
  NVIC_SystemReset();
}
