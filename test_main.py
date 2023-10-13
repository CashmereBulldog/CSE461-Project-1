import pytest

def test_main():
  main()

  # Use pytest.raises without specifying an exception type to assert no exception
  with pytest.raises(Exception, match=""):
      pass
