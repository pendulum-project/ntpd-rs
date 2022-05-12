set yrange [-440:-370]
set xtics (0, "glitch" 4095)
set ytics ("10^8-410" -410, -400, -390, -380, -420, -430)
set xlabel "time (arbitrary)"
set ylabel "clock cycles per second"
plot '../meetlogboek/ref-10-05-2022-1342-analysis/gm-interval.dat' using ($1-100000000) pt 7 black title "Period of GM clock in cycles"
