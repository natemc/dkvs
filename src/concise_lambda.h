#pragma once

#define L0(e) [&](){return e;}
#define L1(e) [&](auto&& x){return e;}
#define L2(e) [&](auto&& x,auto&& y){return e;}
