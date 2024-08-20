
#include "keys/encryptor.h"


#include <memory>
#include <thread>

#include "vm/cells.h"
#include "vm/cellslice.h"
#include "vm/vm.h"
#include "vm/cp0.h"
#include "vm/dict.h"
#include "vm/boc.h"

#include "vm/box.hpp"
#include "vm/atom.h"

#include "smc-envelope/WalletV4.h"

#include <iostream>
#include <fstream>

int main() {

  vm::Dictionary dict{267};

  long amount = 1;
  for (auto i=0;i<20000;i++) {
    auto priv_key = td::Ed25519::generate_private_key().move_as_ok();
    auto pub_key = priv_key.get_public_key().move_as_ok();
    ton::WalletV4::InitData init_data;
    init_data.public_key = pub_key.as_octet_string();
    init_data.wallet_id = 239;

    auto wallet = ton::WalletV4::create(init_data, 2);
    auto address = wallet->get_address();

    vm::CellBuilder my_addr;
    my_addr.store_long_bool(2, 2);
    my_addr.store_long(0, 9) ;
    my_addr.store_bits_bool(address.addr.cbits(), 256);
    auto addr_bits = my_addr.as_cellslice().as_bitslice().bits();

    vm::CellBuilder cb;
    block::tlb::VarInteger grams(16);

    if (amount > 10000) {
      amount = 1;
    }

    auto value = td::make_bigint(amount*1000);
    grams.store_integer_value(cb, value);
    cb.store_long(1723189734, 48);
    cb.store_long(2070247734, 48);
    auto ok =  dict.set(addr_bits, 267, cb.as_cellslice_ref(), vm::Dictionary::SetMode::Add);
    if (!ok) {
      std::cout << "not ok";
      return 0;
    }
    amount += 1;
  };

  auto root = dict.get_root_cell();
  auto result = vm::std_boc_serialize(root).move_as_ok();

  std::ofstream myfile;
  myfile.open ("accounts.boc");
  myfile << td::buffer_to_hex(result.as_slice()) ;
  myfile.close();

  std::cout << "done" << std::endl;

  return 0;
}
