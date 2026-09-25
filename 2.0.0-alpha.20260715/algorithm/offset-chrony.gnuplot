set yrange [10:70]
set xrange [0:3600]
set xlabel "time (s)"
set ylabel "offset (us)"
plot 'offset-chrony.dat' using ($1/100) pt 7 black title "Offset to server"
