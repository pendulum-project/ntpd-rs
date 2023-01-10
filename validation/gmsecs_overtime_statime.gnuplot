set yrange [-375:-325]
set xtics (0)
set ytics ("10^8-350" -350, -325, -330, -335, -340, -345, -355, -360, -365, -370, -375)
set xlabel "time (arbitrary)"
set ylabel "clock cycles per second"
plot '../meetlogboek/statime-soft-31-03-2022-0928-analysis/gm-interval.dat' using ($1-100000000) pt 7 black title "Period of GM clock in cycles"
