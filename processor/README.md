
## PURPOSE

This directory contains the script used to process the raw `.pcap` files captured by the `wireless-crawler`.

The script with process `.pcap` files into a sequence of packets where each packet is represented by its timestamp 
and directional length (direction length is packet length multiplied by direction). 
This is the same format seen in other website fingerprinting works.

## USAGE

1) Install prerequisite python libraries as defined in this project's `requirements.txt` (ex. `pip install -r requirements.txt`)
2) First, edit the `TARGETS` variable in `parser.py` to include the addresses of the NICs whose traffic was captured.
3) Run the script, providing three arguments `--INPUT`, `--OUTPUT`, and `--TYPE`.
   * `--INPUT`  -- argument should be the path to the root directory of your captures
   * `--OUTPUT` -- argument should be the path to the directory where parsed traces should be stored
   * `--TYPE`   -- argument should be either `default` for in-network captures, or `raw` for out-of-network wireless captures.
   * (Optional) `--SITES` -- path to a json file which maps site names to numbers

