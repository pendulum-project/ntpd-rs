set yrange [-407:-393]
set xtics (0, "glitch" 4095)
set ytics ("10^8-400" -400, -405, -395)
set xlabel "time (arbitrary)"
set ylabel "clock cycles per second"
plot '../meetlogboek/ref-18-03-2022-1446-analysis/gm-interval.dat' using ($1-100000000) pt 7 black title "Period of GM clock in cycles"
