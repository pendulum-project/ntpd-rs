set boxwidth 10.00004300
set style fill solid 1 border lt -1
set style rectangle black
set xrange [-6000:2000]
set xlabel "offset (ns)"
set ytics (0)
set yrange [0:35]
plot '../meetlogboek/statime-hard-10-05-2022-1456-analysis/nic-offset.dat' using ($1*10.00004300) smooth freq with boxes fillcolor black title "# of measurements"
