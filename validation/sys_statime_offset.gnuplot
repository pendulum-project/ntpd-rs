set boxwidth 10.00003620
set style fill solid 1 border lt -1
set style rectangle black
set xrange [-95000:35000]
set xlabel "offset (ns)"
set ytics (0)
set yrange [0:20]
plot '../meetlogboek/statime-soft-31-03-2022-0928-analysis/sys-offset.dat' using ($1*10.00003620) smooth freq with boxes fillcolor black title "# of measurements"
