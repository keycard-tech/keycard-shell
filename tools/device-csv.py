# quick tool to convert factory csv of serial numbers/public keys to importable csv.
# committed for transparency but is of no use for development

import argparse
import csv

def t(field):
    return field.replace('"', '')

def main():
    parser = argparse.ArgumentParser(description='Convert factory csv to db import csv')
    parser.add_argument('-f', '--file', help="the csv file")
    parser.add_argument('-o', '--output', help="the output file")
    parser.add_argument('-b', '--batch', help="order/batch combination to filter for")
    args = parser.parse_args()
    with open(args.file, newline='') as in_file:
        with open(args.output, mode='w') as out_file:
            in_csv = csv.reader(in_file, quotechar=None)
            for dev in in_csv:
                batchId = f'{t(dev[1])}-{t(dev[2])}'
                if batchId == args.batch:
                    out_file.write(f'{t(dev[3])},{t(dev[4])}\r\n')

if __name__ == "__main__":
    main()