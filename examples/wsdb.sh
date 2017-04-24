sudo rm .wsdb.pid
cd WSDB && python webServerWSDB.py -s &  
echo $! > .wsdb.pid
