# Raw binaries

For raw binaries or unknown formats, Ghidra will refuse to auto-load. Discover the
right spec then pass it:

```bash
ghidra-decomp --list-languages | grep -i arm
ghidra-decomp ./firmware.bin --language ARM:LE:32:v7 --compiler default
```

Raw binaries typically also need a known image base and an entry point for
auto-analysis to reach every function. Both are applied *before* analysis runs, so
function boundaries, xrefs, and switch-table recovery all happen at the real addresses:

```bash
ghidra-decomp ./dal_ivm.mod \
  --language x86:LE:32:default \
  --compiler gcc \
  --base-addr 0x00031000 \
  --entry   0x00031000
```
