set boxwidth 1
set style fill solid 1 border lt -1
set style rectangle black
set ytics (0)
set xtics ("10^8-400" -400, -405, -395) scale 0
set xlabel "Clock cycles per second"
set xrange [-408:-392]
set yrange [0:2700]
plot '../meetlogboek/ref-18-03-2022-1446-analysis/gm-interval.dat' using ($1-100000000) smooth freq with boxes fillcolor black title "# of measurements"
