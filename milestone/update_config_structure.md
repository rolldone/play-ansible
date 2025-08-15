# Milestone: Update `config.yaml` Structure

## Objective
- Modify `config.yaml` to support individual `username`, `private_key`, `password`, and `port` for each host.
- Update the script to prioritize private keys for authentication, validate required fields, and handle errors.

## Tasks
1. **Update `config.yaml` Structure**:
   - Add `username`, `private_key`, `password`, and `port` fields for each host.
   - Example structure:
     ```yaml
     hosts:
       - ip: "134.209.109.179"
         username: "user1"
         private_key: "path/to/key1"
         password: "password1"
         port: 22
     ```
   - If `port` is not specified, default to `22`.

   - **Status**: Completed

2. **Breakdown for `main.py`**:
   - **Validation**:
     - Validate presence of required fields (`username`, `private_key`, `password`, `port`).
     - Validate format of private keys, passwords, and ports.
     - Throw errors for missing or invalid values.
   - **Task Execution**:
     - Modularize SSH connection simulation and playbook execution.
     - Ensure error handling and stop execution on failure.
   - **Logging**:
     - Create dynamic log files with timestamps.
   - **Main Workflow**:
     - Combine all components into a streamlined workflow in the `main()` function.

   - **Status**: Completed

3. **Testing**:
   - Test the updated script with various configurations to ensure proper error handling and authentication prioritization.

   - **Status**: Pending

4. **Documentation**:
   - Document the new structure and behavior for `config.yaml`.

   - **Status**: Pending

## Timeline
- **Day 1**: Update `config.yaml` structure.
- **Day 2**: Implement script changes for authentication prioritization and validation.
- **Day 3**: Add error handling and format validation.
- **Day 4**: Test the updated script with different configurations.
- **Day 5**: Write documentation for the new structure and behavior.
