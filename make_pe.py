import shutil

# Take a benign Windows binary
src = 'C:\\Windows\\System32\\find.exe'
dst = 'C:\\Projects\\hack2\\APT_Test_Sample_Lazarus.exe'
shutil.copy(src, dst)

# Append our Lazarus behavioral indicators to the overlay
with open(dst, 'ab') as f_out:
    f_out.write(b'\n\n=== BEGIN BEHAVIORAL INDICATORS ===\n')
    with open('C:\\Projects\\hack2\\APT_Test_Sample_Lazarus.txt', 'rb') as f_in:
        f_out.write(f_in.read())
        
print(f"Successfully generated {dst}")
