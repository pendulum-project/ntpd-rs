set yrange [-95000:45000]
set xtics (0)
set xlabel "time (arbitrary)"
set ylabel "offset (ns)"
plot '../meetlogboek/statime-soft-31-03-2022-0928-analysis/sys-offset.dat' using ($1*10.00003620) pt 7 black title "Offset of system clock to GM"
