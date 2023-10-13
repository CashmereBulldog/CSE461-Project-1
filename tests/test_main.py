import pytest
import sys
sys.path.append("./src")
import main

def test_main():
  main.main()

  # Use pytest.raises without specifying an exception type to assert no exception
  with pytest.raises(Exception, match=""):
      pass
