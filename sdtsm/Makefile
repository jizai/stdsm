CC = gcc
OPT = -O2
TGT = libsdtsm.so
OBJ = SM3.o SM2.o SM4.o SdtSM.o

all: $(TGT) $(APP)

$(OBJ): %o:%c
	$(CC) -c $(CFLAGS) -fPIC $? -o $@ $(OPT)

$(TGT):$(OBJ) 
	$(CC) $(CFLAGS) -shared -fPIC -o $(TGT) $(OBJ) 
	cp libsdtsm.so ../lib
	
clean:
	rm -rf *.o *.bak $(TGT) $(APP)
