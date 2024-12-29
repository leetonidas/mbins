#pragma once

#include <iostream>
#include <sstream>

#include <cstdint>
#include <bit>
#include <cstring>

/*
template <typename regtype, unsigned numregs>
struct Context{
	typedef regtype rty;
	typename Context::rty regs[numregs];

};
*/
namespace {

template <typename regtype, unsigned numregs, bool encryption>
struct Context{
	typedef regtype rty;
	typename Context::rty regs[numregs];
	uint8_t *data = nullptr, *dataend = nullptr;
};

template <typename regtype, unsigned numregs>
struct Context<regtype, numregs, true> {
	typedef regtype rty;
	typename Context::rty regs[numregs];
	uint8_t *data = nullptr, *dataend = nullptr;
	uint32_t lfsr = 0;
};

template <typename T>
__attribute__((always_inline))
uint32_t getNext32(T &ctx) {
	(void) ctx;
	return 0;
}

template <typename regtype, unsigned numregs>
__attribute__((always_inline))
uint32_t getNext32(Context<regtype, numregs, true> &ctx) {
	uint32_t tmp;
	tmp = ctx.lfsr;
	tmp ^= tmp << 13;
	tmp ^= tmp >> 17;
	tmp ^= tmp << 5;
	ctx.lfsr = tmp;
	return tmp;
}

template <typename regtype, unsigned numregs, bool encryption>
__attribute__((always_inline))
uint64_t callout(Context<regtype, numregs, encryption> &ctx, uint64_t tar, uint32_t numargs) {
	//printf("calling function @%p with %u arguments\n", pc, numargs);
	uint64_t * stack = (uint64_t *)ctx.regs[30];
	__attribute__((aligned(16))) uint64_t stackargs[numargs];
#ifdef __x86_64__
	typedef uint64_t (*fun_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
	if (numargs > 6) {
		stackargs[0] = ctx.regs[6];
		stackargs[1] = ctx.regs[7];
		memcpy(&stackargs[2], &stack, (numargs - 8) * sizeof(uint64_t));
	}
	return ((fun_t)tar)(ctx.regs[0], ctx.regs[1], ctx.regs[2], ctx.regs[3], ctx.regs[4], ctx.regs[5]);
#elif defined(__aarch64__)
	typedef uint64_t (*fun_t)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
	if (numargs > 8)
		memcpy(stackargs, stack, (numargs - 8) * sizeof(uint64_t));
	return ((fun_t)tar)(ctx.regs[0], ctx.regs[1], ctx.regs[2], ctx.regs[3], ctx.regs[4], ctx.regs[5], ctx.regs[6], ctx.regs[7]);
#else
#error "architecture not supported"
#endif
}

template <std::endian ope, typename regtype, unsigned numregs, bool encryption>
__attribute__((noinline))
void step(Context<regtype,numregs, encryption> &ctx) {
	uint32_t opcode = *(uint32_t*)ctx.regs[numregs - 1];
	uint64_t ip = ctx.regs[numregs - 1] - (uint64_t) ctx.data;
	//std::cerr << "Opcode: " << std::hex << opcode << std::endl;
	ctx.regs[numregs - 1] += 4;
	if constexpr (std::endian::native != ope) {
		opcode = std::byteswap(opcode);
	}

	if constexpr (encryption) {
		if (ctx.lfsr == 0) {
			ctx.lfsr = opcode;
//			std::cerr << "setting lfsr to " << std::hex << ctx.lfsr << std::dec << "\n";
			return;
		}
		//std::cerr << "lfsr: " << std::hex << ctx.lfsr << std::endl;
		opcode = opcode ^ getNext32(ctx);
	}

	//std::cerr << "opcode: " << std::hex << opcode << std::dec << "\n";

	if constexpr (encryption) {
//		std::cerr << "[" << std::hex << ip << " (" << ctx.lfsr << ")] " << std::dec << std::endl;
	} else {
//		std::cerr << "[" << std::hex << ip << "] " << std::dec << std::endl;
	}

	uint32_t opkind = opcode >> 29;

	if (opkind == 0 || (opkind == 1 && ((opcode >> 28u) & 1) == 0)) {
//		std::stringstream op_arg;
		uint_fast16_t rr = (opcode >> 19u) & 0x1fu;
		uint64_t arg1 = ctx.regs[(opcode >> 14u) & 0x1fu];
//		op_arg << "r" << rr << ", " << "r" << ((opcode >> 14u) & 0x1fu) << ", ";
		uint64_t arg2 = 0u;
		bool imm = false;
		if (opkind == 0u && ((opcode >> 24u) & 1u) == 0u)
			imm = true;
		if (opkind == 1u && ((opcode >> 24u) & 1u) == 1u)
			imm = true;
		if (imm) {
			if (opcode >> 25u == 7u || opcode >> 25u == 9u || opkind == 1) {
				arg2 = (((int64_t) opcode << 50l) >> 50l);
				//std::cerr << "signed 14 bit - " << arg2 << std::endl;
			} else {
				arg2 = opcode & 0x3fff;
				//std::cerr << "unsigned 14 bit - " << arg2 << std::endl;
			}
			//std::cerr << "imm: " << arg2 << std::endl;
//			op_arg << std::hex << "0x" << arg2;
		} else {
			arg2 = ctx.regs[(opcode >> 9u) & 0x1f];
//			op_arg << "r" << ((opcode >> 9u) & 0x1f);
		}

		uint64_t res = 0;
		if (opkind == 1) {
			switch ((opcode >> 25u) & 0x7u) {
			case 0: // SETEQ
//				std::cerr << "SETEQ " << op_arg.str() << std::endl;
				res = arg1 == arg2;
				break;
			case 1: // SETNE
//				std::cerr << "SETNE " << op_arg.str() << std::endl;
				res = arg1 != arg2;
				break;
			case 2: // SETLE
//				std::cerr << "SETLE " << op_arg.str() << std::endl;
				res = (int64_t) arg1 <= (int64_t) arg2;
				break;
			case 3: // SETLT
//				std::cerr << "SETLT " << op_arg.str() << std::endl;
				res = (int64_t) arg1 < (int64_t) arg2;
				break;
			case 4: // SETULE
//				std::cerr << "SETULE " << op_arg.str() << std::endl;
				res = arg1 <= arg2;
				break;
			case 5: // SETULT
//				std::cerr << "SETULT " << op_arg.str() << std::endl;
				res = arg1 < arg2;
				break;
			}
		} else {
			switch ((opcode >> 25u) & 0xfu) {
			case 0: // OR
//				std::cerr << "OR " << op_arg.str() << std::endl;
				res = arg1 | arg2;
				break;
			case 1: // XOR
//				std::cerr << "XOR " << op_arg.str() << std::endl;
				res = arg1 ^ arg2;
				break;
			case 2: // AND
//				std::cerr << "AND " << op_arg.str() << std::endl;
				res = arg1 & arg2;
				break;
			case 3: // ADD
//				std::cerr << "ADD " << op_arg.str() << std::endl;
				res = arg1 + arg2;
				break;
			case 4: // SUB
//				std::cerr << "SUB " << op_arg.str() << std::endl;
				res = arg1 - arg2;
				break;
			case 5: // MUL
//				std::cerr << "MUL " << op_arg.str() << std::endl;
				res = arg1 * arg2;
				break;
			case 6: // DIV
//				std::cerr << "DIV " << op_arg.str() << std::endl;
				res = arg1 / arg2;
				break;
			case 7: // SDIV
//				std::cerr << "SDIV " << op_arg.str() << std::endl;
				res = (int64_t) arg1 / (int64_t) arg2;
				break;
			case 8: // REM
//				std::cerr << "REM " << op_arg.str() << std::endl;
				res = arg1 % arg2;
				break;
			case 9: // SREM
//				std::cerr << "SREM " << op_arg.str() << std::endl;
				res = (int64_t) arg1 % (int64_t) arg2;
				break;
			case 10:
//				std::cerr << "SHL " << op_arg.str() << std::endl;
				res = arg1 << arg2;
				break;
			case 11:
//				std::cerr << "SAR " << op_arg.str() << std::endl;
				res = (int64_t) arg1 >> (int64_t) arg2;
				break;
			case 12:
//				std::cerr << "SLR " << op_arg.str() << std::endl;
				res = arg1 >> arg2;
				break;
			case 13:
//				std::cerr << "ROTL " << op_arg.str() << std::endl;
				res = (arg1 << arg2) | (arg1 >> (64 - arg2));
				break;
			case 14:
//				std::cerr << "ROTR " << op_arg.str() << std::endl;
				res = (arg1 >> arg2) | (arg1 << (64 - arg2));
				break;
			}
		}
		ctx.regs[rr] = res;
		return;
	}

	if (opkind == 1) {
		opkind = (opcode >> 26) & 3;
		if (opkind == 0) {
//			std::cerr << "RET" << std::endl;
			// ret
			uint64_t *sp = (uint64_t*) ctx.regs[numregs - 2];
			ctx.regs[numregs - 1] = *sp;
			if constexpr (encryption) {
				ctx.lfsr = *(++sp);
			}
			ctx.regs[numregs - 2] = (uint64_t) (++sp);
			return;
		}

		if (opkind == 2) {
			// call
//			std::cerr << "CALL" << std::endl;
			uint64_t tar = ctx.regs[(opcode >> 20) & 0x1f];
			if ((uint64_t) ctx.data <= tar && tar < (uint64_t) ctx.dataend) {
				uint64_t *sp = (uint64_t*) ctx.regs[numregs - 2];
				if constexpr (encryption) {
					*(--sp) = ctx.lfsr;
					ctx.lfsr = 0;
				}
				*(--sp) = ctx.regs[numregs - 1];
				ctx.regs[numregs - 1] = ctx.regs[(opcode >> 20) & 0x1f];
				ctx.regs[numregs - 2] = (uint64_t) sp;
			} else {
				uint32_t numargs = opcode & 0xfffff;
				uint64_t sav_pc = ctx.regs[numregs - 1];
				uint64_t sav_lfsr;
				if constexpr (encryption)
					sav_lfsr = ctx.lfsr;
				ctx.regs[0] = callout(ctx, tar, numargs);
				if constexpr (encryption)
					ctx.lfsr = sav_lfsr;
				ctx.regs[numregs - 1] = sav_pc;
			}
			return;
		}

		uint32_t cor = *(uint32_t*) ctx.regs[31];
		if constexpr (std::endian::native != ope)
			cor = std::byteswap(cor);
		cor ^= getNext32(ctx);

		if ((opcode >> 25) & 1) {
			// BR
			int64_t imm = (opcode & 0x1ffffff);
			imm = (imm << 39l) >> 39l;
			imm <<= 2;
//			std::cerr << "BR " << imm << std::endl;
			ctx.regs[31] += imm - 4;
			if constexpr (encryption) {
//				std::cerr << "new lfsr due to branch taken: " << std::hex << cor << std::dec << std::endl;
				ctx.lfsr = cor;
			}
		} else {
			// BRCC
			uint_fast16_t rr = (opcode >> 20) & 0x1f;
			int64_t imm = (opcode & 0xfffff);
			imm = (imm << 44l) >> 44l;
			imm <<= 2;
//			std::cerr << "BRCC r" << rr << ", " << imm << std::endl;
			if (ctx.regs[rr]) {
				ctx.regs[31] += imm - 4;
				if constexpr (encryption) {
//					std::cerr << "new lfsr due to branch taken: " << std::hex << cor << std::dec << std::endl;
					ctx.lfsr = cor;
				}
			}
			else if constexpr (encryption)
				ctx.regs[31] += 4;
			return;
		}
	}

	if (opkind == 2) {
		opkind = (opcode >> 27) & 3;
		if (opkind == 0) {
			uint_fast16_t rr = (opcode >> 16) & 0x1f;
			uint64_t imm = *(uint64_t*) ctx.regs[31];
			if constexpr (std::endian::native != ope)
				imm = std::byteswap(imm);

			if constexpr (encryption) {
				uint64_t xorval = 0;
				if constexpr (std::endian::big == ope) {
					xorval = ((uint64_t) getNext32(ctx)) << 32;
					xorval |= getNext32(ctx);
				} else {
					xorval = getNext32(ctx);
					xorval |= ((uint64_t) getNext32(ctx)) << 32;
				}
				imm ^= xorval;
			}
			ctx.regs[31] += 8;
//			std::cerr << "LDI r" << rr << ", " << imm << std::endl;
			ctx.regs[rr] = imm;
			return;
		}

		unsigned reg = (opcode >> 21) & 0x1f;
		unsigned base = (opcode >> 16) & 0x1f;
		int64_t disp = opcode & 0xffff;
		if ((opcode >> 15) & 1)
			disp = disp - 0x8000;

		if (opkind == 1) {
//			std::cerr << "LD r" << reg << ", [r" << base << " + " << disp << "]" << std::endl;
			ctx.regs[reg] = *(uint64_t*)(ctx.regs[base] + disp);
		} else {
			unsigned width = (opcode >> 26) & 3;
			switch (width) {
			case 0:
//				std::cerr << "STB [r" << base << " + " << disp << "]" << ", r" << reg << std::endl;
				*(uint8_t*)(ctx.regs[base] + disp) = ctx.regs[reg];
				break;
			case 1:
//				std::cerr << "STQ [r" << base << " + " << disp << "]" << ", r" << reg << std::endl;
				*(uint16_t*)(ctx.regs[base] + disp) = ctx.regs[reg];
				break;
			case 2:
//				std::cerr << "STH [r" << base << " + " << disp << "]" << ", r" << reg << std::endl;
				*(uint32_t*)(ctx.regs[base] + disp) = ctx.regs[reg];
				break;
			case 3:
//				std::cerr << "ST [r" << base << " + " << disp << "]" << ", r" << reg << std::endl;
				*(uint64_t*)(ctx.regs[base] + disp) = ctx.regs[reg];
				break;
			}
		}

		return;
	}

}

}