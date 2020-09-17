Running: python endtoendanalyzer.py

Example usage is in endtoendanalyzer:main.


All pcaps go in the captures/ directory. Plot stats should also be in the captures directory, with file ending '.plt_stats'.

## requirements

* python3
* python3-numpy

On Debian-based machines: `apt install python3 python3-numpy`.

## usage

1. Place `*.pcap` and `*.pcapng` files in `captures/`
2. Save Page Load Time statistics (saved as `*.plt_stats`) to `captures/`
3. Run analysis: `cd end_to_end_rdns_analysis/analysis_scripts && python3 endtoendanalyzer.py`
4. Read output: `cat end_to_end_rdns_analysis/out.txt`
