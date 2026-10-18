import os
import sys
from pathlib import Path
from slither import Slither

sol_path = sys.argv[1]
# Ensure solc in PATH
solc_dir = str(Path.home() / '.solc-select' / 'artifacts' / 'solc-0.8.19')
venv_scripts = str(Path('.venv/Scripts').resolve())
os.environ['PATH'] = f'{venv_scripts};{solc_dir};' + os.environ.get('PATH', '')

sl = Slither(sol_path)
for contract in sl.contracts:
    for fn in contract.functions_declared:
        fn_id = f'{contract.name}.{fn.full_name}'
        vis = fn.visibility
        is_cons = fn.is_constructor
        is_impl = fn.is_implemented
        mods = [m.name for m in fn.modifiers]
        internal_call_types = [type(item).__name__ for item in fn.internal_calls]
        high_level_shapes = [type(item).__name__ for item in fn.high_level_calls]
        low_level_calls = [c.name if hasattr(c, 'name') else str(c) for c in fn.low_level_calls]
        vars_read = [v.name for v in fn.state_variables_read]
        vars_written = [v.name for v in fn.state_variables_written]
        try:
            protected = fn.is_protected()
        except Exception as e:
            protected = False
        print(f'{fn_id} | vis={vis} | is_cons={is_cons} | is_impl={is_impl} | mods={mods} | protected={protected} | int_calls={internal_call_types} | high_calls={high_level_shapes} | low_calls={low_level_calls} | read={vars_read} | write={vars_written}')
