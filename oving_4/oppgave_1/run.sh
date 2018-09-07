./hello 2> stderr_output
echo "Exit code: $?"
echo "Output to stderr:"
cat stderr_output
rm stderr_output
