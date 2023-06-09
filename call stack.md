```python
## Trace Comparison
MP-SPDZ/Compiler/types.py: 2117 `class sint`
MP-SPDZ/Compiler/types.py: 2439 `comparison.LTZ`
MP-SPDZ/Compiler/comparison.py: 80 `program.nonlinear.ltz`
 ⁃ configured here: MP-SPDZ/Compiler/program.py: 215 `self.non_linear = Ring(ring_size)`
MP-SPDZ/Compiler/non_linear.py: 191 `LtzRing(...)`
MP-SPDZ/Compiler/comparison.py: 87 `CarryOutRawLE(...)`
MP-SPDZ/Compiler/comparison.py: 459 `CarryOutRaw(...)`
MP-SPDZ/Compiler/comparison.py: 452 `bit_and(...)`
MP-SPDZ/Compiler/GC/types.py: 851 `self & other`
MP-SPDZ/Compiler/GC/types.py: 195 `self._and(...)`
MP-SPDZ/Compiler/GC/types.py: 503 `inst.ands(...)`
MP-SPDZ/Compiler/GC/instructions.py: 159 `class ands`
MP-SPDZ/Compiler/GC/instructions.py: 79 `class BinaryVectorInstruction`
MP-SPDZ/Compiler/instruction_base.py: 791 `class Instruction`
MP-SPDZ/Compiler/instruction_base.py: 806 `program.curr_block.instructions.append(self)`
```

```python
## Trace Truncation
types.py: 2553 `__rshift__`
comparison.py: 111 `Trunc`
non_linear.py: 92 `_trunc`

```