set yrange [-3600:-3300]
set xlabel "time (arbitrary)"
set ylabel "offset (ns)"
plot '../meetlogboek/ref-10-05-2022-1342-analysis/nic-offset.dat' using ($1*10.00004010) pt 7 black title "Offset of system clock to GM"
