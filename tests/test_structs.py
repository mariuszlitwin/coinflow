import pytest
import time
from datetime import datetime, timezone

from coinflow.protocol.structs import *

def test_varint():
    uint8_t = Varint(0x10)
    uint16_t = Varint(0x1000)
    uint32_t = Varint(0x10000000)
    uint64_t = Varint(0x1000000000000000)

    assert Varint.decode(uint8_t.encode())  == (0x10, 1)
    assert Varint.decode(uint16_t.encode()) == (0x1000, 3)
    assert Varint.decode(uint32_t.encode()) == (0x10000000, 5)
    assert Varint.decode(uint64_t.encode()) == (0x1000000000000000, 7)
    
def test_varstr():
    short = 'Hello world'
    rlong = '''
    Lorem ipsum dolor sit amet, consectetur adipiscing elit. Duis dignissim ante id auctor ultrices. Vestibulum vitae nisl nisi. Morbi et pretium elit. Suspendisse eget cursus eros, vitae convallis massa. Suspendisse ullamcorper neque a lacus consectetur, at lobortis dui feugiat. Maecenas sit amet justo finibus, vehicula justo at, porttitor lacus. Integer mollis faucibus urna eu interdum. Maecenas aliquam dolor a eleifend ullamcorper. Nulla imperdiet ipsum eu posuere sagittis. Integer eu ultricies risus, eu faucibus eros. In ac nibh vitae quam varius dictum. Interdum et malesuada fames ac ante ipsum primis in faucibus. In nunc libero, lobortis non metus ac, lobortis tempor lacus. In justo nibh, pretium vel mollis eget, semper at nibh. Pellentesque ac elit metus. Nullam lorem turpis, congue vel sapien et, porta varius lacus.

    Sed sed erat at turpis lobortis elementum quis vitae felis. In vitae lacinia lorem. Aenean pulvinar nisl velit, in lobortis justo pellentesque et. Aenean et tellus ac ligula mattis condimentum. Vestibulum efficitur tristique enim, vel rhoncus diam. Aliquam varius gravida augue. Sed suscipit elit in porta consectetur. Morbi blandit viverra consectetur. Fusce congue massa neque. In lobortis est sed congue fermentum.

    Suspendisse tristique dui pharetra leo laoreet sodales. Sed scelerisque est orci. Mauris eget diam viverra mi lobortis pulvinar eget nec urna. Quisque tellus leo, ornare quis nisi sed, consequat mollis ligula. Ut porta sapien sed tellus gravida dictum. Proin rutrum tortor sed lacus fermentum, et mollis diam dictum. Pellentesque pulvinar sed nunc et sagittis. Suspendisse fringilla tortor vitae arcu euismod ullamcorper.

    Fusce aliquam lectus nibh, non facilisis arcu scelerisque sit amet. Aenean a ante nunc. Integer et ligula a lacus tempus consequat. Sed finibus, neque ut aliquam rutrum, risus tellus euismod magna, eget iaculis sem tellus at elit. Pellentesque condimentum faucibus metus in euismod. Ut porttitor malesuada mi. Nulla eu urna rutrum, vehicula elit vitae, fringilla nulla. Donec dictum facilisis aliquam. Nulla facilisi. Vestibulum vel dolor quis eros eleifend vestibulum in non odio. Aliquam luctus sapien est, sit amet tempus libero imperdiet dignissim. Suspendisse pellentesque enim a diam consectetur, eget euismod risus suscipit. Morbi tempor ex erat, vitae auctor erat cursus a. Nam vitae tincidunt ipsum.

    Vestibulum nec leo justo. Nulla ornare efficitur neque, vitae tincidunt justo ultricies id. Fusce congue sapien eu est molestie sodales. Donec facilisis est at augue vehicula blandit. Quisque blandit felis iaculis, vestibulum nisi non, dignissim urna. Quisque ut viverra lorem. Etiam quis elit enim. Curabitur vitae fringilla sapien, eu accumsan metus. Nunc et turpis nec massa maximus scelerisque. Mauris a vestibulum quam. Fusce sit amet leo non urna hendrerit rhoncus eu eget odio. Aliquam vel volutpat magna, nec laoreet tellus. Nullam eros lacus, placerat nec tempus eu, dictum non ipsum. Vestibulum nec rutrum dolor. Donec congue augue purus, in iaculis mauris malesuada sed. Aliquam erat volutpat.
    '''
    short_enc = Varstr(short)
    rlong_enc = Varstr(rlong)

    assert Varstr.decode(short_enc.encode()) == (short, Varint(len(short_enc)))
    assert Varstr.decode(rlong_enc.encode()) == (rlong, Varint(len(rlong_enc)))

def test_netaddr():
    na = Netaddr('127.0.0.1', 8333, 0)

    na_c = Netaddr.from_raw(na.encode())
    
    with pytest.raises(TypeError):
        na.ip = '192.168.1.1'
    with pytest.raises(TypeError):
        na.port = '22'
    with pytest.raises(TypeError):
        na.services = '11'

    assert na_c == na

def test_timestamp():
    enc_ts = Timestamp(2017, 1, 1, 10, 0, 0)
    assert Timestamp.from_raw(enc_ts.encode()) == enc_ts
