# SECURITY DEFINER functions

`SECURITY DEFINER` functions execute with owner privileges, so direct table RLS
results do not establish function authorization safety. pg-canary inspects their
owner, definer status, and configured search path as advisory evidence only.

The tool does not execute arbitrary definer functions. Testing one requires an
explicit function-specific profile, input contract, side-effect review, and a
separate threat model.
