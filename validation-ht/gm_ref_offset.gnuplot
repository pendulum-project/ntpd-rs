set boxwidth 10.00004270
set style fill solid 1 border lt -1
set style rectangle black
set xrange [-3550:-3350]
set xlabel "offset (ns)"
set ytics (0)
set yrange [0:600]
plot '../meetlogboek/ref-10-05-2022-1342-analysis/nic-offset.dat' using ($1*10.00004270) smooth freq with boxes fillcolor black title "# of measurements"
