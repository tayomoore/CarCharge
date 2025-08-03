#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Build the SAM application
sam build

# Deploy the SAM application
sam deploy --guided
