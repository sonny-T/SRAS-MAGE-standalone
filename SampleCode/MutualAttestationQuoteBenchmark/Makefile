DEBUG ?= 0

PRIMARY_REPO_ROOT ?= $(abspath $(CURDIR)/../../../..)
SGX_SDK ?= $(PRIMARY_REPO_ROOT)/linux/installer/common/sdk/output/package
PSW_LIB_ROOT ?= $(PRIMARY_REPO_ROOT)/build/linux
SGX_MODE ?= HW
SGX_ARCH ?= x64

SYSTEM_DCAP_INCLUDE ?= /usr/include
SYSTEM_DCAP_LIB ?= /usr/lib/x86_64-linux-gnu
DCAP_WRAPPER_ROOT ?= $(PRIMARY_REPO_ROOT)/external/dcap_source/QuoteGeneration/quote_wrapper
DCAP_WRAPPER_QL_INCLUDE ?= $(DCAP_WRAPPER_ROOT)/ql/inc
DCAP_WRAPPER_COMMON_INCLUDE ?= $(DCAP_WRAPPER_ROOT)/common/inc
DCAP_PCE_INCLUDE ?= $(PRIMARY_REPO_ROOT)/external/dcap_source/QuoteGeneration/pce_wrapper/inc
LEGACY_SGX_INCLUDE ?= /opt/intel/sgxsdk/include

SGX_COMMON_CFLAGS := -m64
SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r

ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

DCAP_Library_Name := sgx_dcap_ql
Urts_Library_Name := sgx_urts
Urts_Library_File := $(PSW_LIB_ROOT)/libsgx_urts.so
Uae_Service_Library_File := $(PSW_LIB_ROOT)/libsgx_uae_service.so

App_Cpp_Files := App/App.cpp
App_Include_Paths := -I$(SGX_SDK)/include -I$(LEGACY_SGX_INCLUDE) -I../../common/inc

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)
ifeq ($(DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
        $(Urts_Library_File) $(Uae_Service_Library_File) -ldl -lpthread \
        -Wl,-rpath,$(PSW_LIB_ROOT) -Wl,-rpath,$(SGX_LIBRARY_PATH) -Wl,-rpath,$(SYSTEM_DCAP_LIB)

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_Name := app

Helper_Cpp_Files := App/QuoteHelper.cpp
Helper_Include_Paths := -I$(SYSTEM_DCAP_INCLUDE) -I$(SGX_SDK)/include \
        -I$(DCAP_WRAPPER_QL_INCLUDE) -I$(DCAP_WRAPPER_COMMON_INCLUDE) -I$(DCAP_PCE_INCLUDE) \
        -I$(LEGACY_SGX_INCLUDE) \
        -I../../common/inc
Helper_Cpp_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(Helper_Include_Paths) -std=c++11
Helper_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SYSTEM_DCAP_LIB) -L$(SGX_LIBRARY_PATH) \
        -l$(DCAP_Library_Name) -lsgx_dcap_quoteverify -ldcap_quoteprov -lsgx_default_qcnl_wrapper \
        -ldl -lpthread -Wl,-rpath,$(SYSTEM_DCAP_LIB) -Wl,-rpath,$(SGX_LIBRARY_PATH)
Helper_Cpp_Objects := $(Helper_Cpp_Files:.cpp=.o)
Helper_Name := quote_helper

Trts_Library_Name := sgx_trts
Service_Library_Name := sgx_tservice
Crypto_Library_Name := sgx_tcrypto
Mage_Library_Path := ../../sdk/mage

Enclave_Cpp_Files := Enclave/Enclave.cpp
Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx -I../../common/inc

CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
        Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector
else
        Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong
endif
Enclave_C_Flags += $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(Mage_Library_Path) \
        -L$(SGX_LIBRARY_PATH) \
        -Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
        -Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_mage -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
        -Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
        -Wl,-pie,-eenclave_entry -Wl,--export-dynamic \
        -Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
        -Wl,-z,relro,-z,now,-z,noexecstack \
        -Wl,--version-script=Enclave/Enclave.lds

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_Name := enclave.so
Signed_Enclave_Names := $(addprefix libenclave,$(addsuffix .so,$(shell seq 1 $(PARTIES))))
Enclave_Config_File := Enclave/Enclave.config.xml
MAGE_FILE ?= mage.bin
MAGE_GEN_OUT ?= genmage.out

ifeq ($(DEBUG), 1)
        Build_Mode = HW_DEBUG
else
        Build_Mode = HW_RELEASE
endif

.PHONY: all target run clean mage-lib

all: .config_$(Build_Mode)_$(SGX_ARCH)
	$(MAKE) target

target: $(App_Name) $(Helper_Name) $(Signed_Enclave_Names)

run: all
	@$(CURDIR)/$(App_Name)

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Names) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.* $(MAGE_FILE) $(MAGE_GEN_OUT)
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

App/Enclave_u.c:
	cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl
	@echo "GEN  =>  $@"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(App_Cpp_Objects): App/Enclave_u.c
App/%.o: App/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o $(App_Cpp_Objects)
	$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

$(Helper_Cpp_Objects): App/Enclave_u.c
App/QuoteHelper.o: App/QuoteHelper.cpp
	@$(CXX) $(Helper_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Helper_Name): $(Helper_Cpp_Objects)
	$(CXX) $^ -o $@ $(Helper_Link_Flags)
	@echo "LINK =>  $@"

Enclave/Enclave_t.c:
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl
	@echo "GEN  =>  $@"

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(Enclave_Cpp_Objects): Enclave/Enclave_t.c
Enclave/%.o: Enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

mage-lib:
	@$(MAKE) -C $(Mage_Library_Path) clean
	@$(MAKE) -C $(Mage_Library_Path) libsgx_mage.a

$(Enclave_Name): mage-lib Enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $(filter %.o,$^) -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

genmage: $(Enclave_Name)
	@rm -f $(MAGE_FILE)
	@for party in $(shell seq 1 $(PARTIES)); do \
		$(SGX_ENCLAVE_SIGNER) genmage -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $(MAGE_GEN_OUT) -config $(Enclave_Config_File) -mageout $(MAGE_FILE); \
	done

$(Signed_Enclave_Names): libenclave%.so: genmage
	@$(SGX_ENCLAVE_SIGNER) signmage -key Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File) -magein $(MAGE_FILE)
	@echo "SIGN =>  $@"

clean:
	@rm -f $(App_Name) $(Helper_Name) App/*.o App/Enclave_u.* .config_*
	@rm -f $(Enclave_Name) $(Signed_Enclave_Names) $(Enclave_Cpp_Objects) Enclave/Enclave_t.* $(MAGE_FILE) $(MAGE_GEN_OUT)
