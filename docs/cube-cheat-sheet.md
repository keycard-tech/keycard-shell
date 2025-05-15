# STM3 Programmer CLI cheatsheet

Some commands useful during development

## Write protect bootloader

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob wrpsgn1=0xfffffffe -ob wrpsgn2=0xfffffffe
```

## Disable write protection

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob wrpsgn1=0xffffffff -ob wrpsgn2=0xffffffff
```

## Product state Provisioning

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob product_state=0x17
```

## Product state Locked

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob product_state=0x5c
```

## Swap banks

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob swap_bank=0
```

## Erase all

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -e all
```

## Erase bootloader

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -e [0 3] -e [128 131]
```

## Erase firmware

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -e [4 79] -e [132 207]
```

## Download full

```shell
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32h5.bin 0x08000000 -v
```

## Download bootloader

```shell
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32-bootloader.bin 0x08000000 -v
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32-bootloader.bin 0x08100000 -v
```

## Download firmware

```shell
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32.bin 0x08008000 -v
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32.bin 0x08108000 -v
```

## Full bootloader replace sequence

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob wrpsgn1=0xffffffff -ob wrpsgn2=0xffffffff
.\STM32_Programmer_CLI.exe -c port=SWD -ob swap_bank=0
.\STM32_Programmer_CLI.exe -c port=SWD -e [0 3] -e [128 131]
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w C:\Users\tanuki\git\keycard-pro\stm32\BL\stm32-bootloader.bin 0x08000000 -v
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w C:\Users\tanuki\git\keycard-pro\stm32\BL\stm32-bootloader.bin 0x08100000 -v
.\STM32_Programmer_CLI.exe -c port=SWD -ob wrpsgn1=0xfffffffe -ob wrpsgn2=0xfffffffe
```

## Full fw replace sequence

```shell
.\STM32_Programmer_CLI.exe -c port=SWD -ob swap_bank=0
.\STM32_Programmer_CLI.exe -c port=SWD -e [4 79] -e [132 207]
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32.bin 0x08008000 -v
.\STM32_Programmer_CLI.exe -c port=SWD --skiperase -w stm32.bin 0x08108000 -v
```
