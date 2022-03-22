set boxwidth 10.00004010
set style fill solid 1 border lt -1
set style rectangle black
set xrange [-4250:-3150]
set xlabel "offset (ns)"
set ytics (0)
set yrange [0:1300]
plot '../meetlogboek/ref-18-03-2022-1446-analysis/nic-offset.dat' using ($1*10.00004010) smooth freq with boxes fillcolor black title "# of measurements"
