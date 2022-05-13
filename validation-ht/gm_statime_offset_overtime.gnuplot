set yrange [-6000:2000]
set xtics (0)
set xlabel "time (arbitrary)"
set ylabel "offset (ns)"
plot '../meetlogboek/statime-hard-10-05-2022-1456-analysis/nic-offset.dat' using ($1*10.00003620) pt 7 black title "Offset of clock to GM"
