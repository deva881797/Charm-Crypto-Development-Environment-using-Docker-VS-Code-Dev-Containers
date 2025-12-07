print("Python Check Ok")

import charm; print('Charm Check OK')

from charm.toolbox.pairinggroup import PairingGroup; print('Charm Toolkit Check OK')

import charm; import inspect, os; print(os.path.dirname(inspect.getfile(charm)))
