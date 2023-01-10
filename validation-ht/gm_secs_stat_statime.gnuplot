set boxwidth 1
set style fill solid 1 border lt -1
set style rectangle black
set ytics (0)
set xtics (-430, -420, -410, "10^8-400" -400, -390) scale 0
set xlabel "Clock cycles per second"
set xrange [-440:-380]
set yrange [0:1000]
plot '../meetlogboek/statime-hard-10-05-2022-1456-analysis/gm-interval.dat' using ($1-100000000) smooth freq with boxes fillcolor black title "# of measurements"
