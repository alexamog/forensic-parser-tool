import os
import pylnk3  # type: ignore

username = os.getlogin()
WIN_RECENT = os.path.join("C:\\", "Users", username, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
OFFICE_RECENT = os.path.join("C:\\", "Users", username, "AppData", "Roaming", "Microsoft", "Office", "Recent")

def lnk_parser(lnk_files: list[str]):
    for lnk_file in lnk_files:
        try:
            lnk: pylnk3.Lnk = pylnk3.parse(lnk_file) #type: ignore
            print(f"{lnk.file}")
            print(f"Creation time: {lnk.creation_time}")
            print(f"Last access: {lnk.access_time}")
            print(f"Logical file size: {lnk.file_size}")
            print(f"Modification time: {lnk.modification_time}")
            print("-------------------")
        except Exception as e:
            print(f"Failed to parse {lnk_file}: {e}")

def file_extraction(path: str):
    """
    Looks at the dir, takes files with .lnk file extension
    """
    lnk_arr = [os.path.join(path, file) for file in os.listdir(path) if file.lower().endswith(".lnk")]
    return lnk_arr

def main():
    lnk_files = file_extraction(WIN_RECENT)
    lnk_parser(lnk_files)

if __name__ == "__main__":
    main()