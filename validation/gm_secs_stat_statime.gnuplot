set boxwidth 1
set style fill solid 1 border lt -1
set style rectangle black
set ytics (0)
set xtics ("10^8-350" -350, -325, -330, -335, -340, -345, -355, -360, -365, -370, -375) scale 0
set xlabel "Clock cycles per second"
set xrange [-375:-325]
set yrange [0:800]
plot '../meetlogboek/statime-soft-31-03-2022-0928-analysis/gm-interval.dat' using ($1-100000000) smooth freq with boxes fillcolor black title "# of measurements"
