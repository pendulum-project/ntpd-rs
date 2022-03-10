set boxwidth 1
set style fill solid 1 border lt -1
set style rectangle black
set ytics (0)
set xtics ("10^8" 0, -4000, -3000, -2000, -1000, "+1000" 1000, "+2000" 2000, "+3000" 3000) scale 0
set xlabel "Clock cycles per second"
set xrange [-4500:3700]
set yrange [0:25]
plot 'gm_sec_interval.dat' using ($1-100000000) smooth freq with boxes fillcolor black title "# of measurements"