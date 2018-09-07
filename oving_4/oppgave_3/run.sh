echo "Running c_example. Output to stdout:"
build/c_example 2> stderr_output
printf "\nOutput to stderr:\n"
cat stderr_output
rm stderr_output
