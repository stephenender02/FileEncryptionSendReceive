test: clean
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo "   Testing STUDENT's Code all with itself"
	@echo "   Validates   Everything before submission"
	@echo "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
	@echo
	gcc amal/amal.c    myCrypto.c   -o amal/amal    -lcrypto
	gcc basim/basim.c  myCrypto.c   -o basim/basim  -lcrypto
	gcc kdc/kdc.c      myCrypto.c   -o kdc/kdc      -lcrypto
	gcc wrappers.c     dispatcher.c -o dispatcher
	ln -f -s ../amal/amalKey.bin        kdc/amalKey.bin
	ln -f -s ../basim/basimKey.bin      kdc/basimKey.bin
	./dispatcher
	@echo
	@echo "======  STUDENT's    KDC    LOG  ========="
	@cat kdc/logKDC.txt
	@echo
	@echo
	@echo "======  STUDENT's    Amal   LOG  ========="
	@cat amal/logAmal.txt
	@echo
	@echo "======  STUDENT's    Basim  LOG  ========="
	@cat basim/logBasim.txt
	@echo

clean:
	rm -f dispatcher   
	rm -f kdc/kdc      kdc/logKDC.txt
	rm -f amal/amal    amal/logAmal.txt  
	rm -f basim/basim  basim/logBasim.txt  


