set yrange [-440:-370]
set xtics (0)
set ytics ("10^8-400" -400, -380, -390, -410, -420, -430)
set xlabel "time (arbitrary)"
set ylabel "clock cycles per second"
plot '../meetlogboek/statime-hard-10-05-2022-1456-analysis/gm-interval.dat' using ($1-100000000) pt 7 black title "Period of GM clock in cycles"
