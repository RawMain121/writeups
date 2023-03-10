import csv
import argparse
import os

# Define arguments
parser = argparse.ArgumentParser(description='Convert Wappalyzer CSV file to Markdown format')
parser.add_argument('-i', '--input', help='Input CSV file', required=True)
parser.add_argument('-o', '--output', help='Output Markdown file')
args = parser.parse_args()

# Read CSV file
with open(args.input, 'r', newline='') as infile:
    reader = csv.reader(infile)
    headers = next(reader)
    data = [row for row in reader]

# Find columns with no values
empty_columns = []
for i, header in enumerate(headers):
    if all(not row[i] for row in data):
        empty_columns.append(i)

# Remove empty columns
headers = [header for i, header in enumerate(headers) if i not in empty_columns]
data = [[cell for i, cell in enumerate(row) if i not in empty_columns] for row in data]

# Determine output file name
if args.output:
    output_filename = args.output
else:
    url_index = headers.index('URL') if 'URL' in headers else 0
    url_value = data[0][url_index].replace('http://', '').replace('https://', '').replace('/', '-').replace(':', '-') + '.md'
    output_filename = "Wappalyzer2MD_" + url_value 

# Write to Markdown file
with open(output_filename, 'w') as outfile:
    # Write headers
    outfile.write('| ' + ' | '.join(headers) + ' |\n')
    outfile.write('| ' + ' | '.join(['---' for header in headers]) + ' |\n')

    # Write data
    for row in data:
        outfile.write('| ' + ' | '.join(row) + ' |\n')
