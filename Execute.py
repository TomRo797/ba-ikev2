""" IMPORTS """
import pyautogui
import time
import os
from analyze import Analyzer

""" Methods """
def execute_tests() -> None:
    IMG_PATH = "C:/Users/Laptop/Desktop/Achelos/Scripts/images/"
    time.sleep(1)

    try: pos1 = pyautogui.locateOnScreen(IMG_PATH + "at_1.PNG", confidence=0.98)
    except pyautogui.ImageNotFoundException: exit("Could not find testcases. Exiting.")

    pyautogui.moveTo(pos1[0]+15, pos1[1]+15, duration=0.5)
    time.sleep(0.5)
    pyautogui.rightClick()
    pyautogui.rightClick()
    time.sleep(0.5)

    try: pos2 = pyautogui.locateOnScreen(IMG_PATH + "at_2.PNG", confidence=0.98)
    except pyautogui.ImageNotFoundException: exit("Could not find 'Execute' Button. Exiting.")
    
    pyautogui.moveTo(pos2[0]+15, pos2[1]+15, duration=0.5)
    time.sleep(0.5)
    pyautogui.click()
    time.sleep(0.5)


""" Main """
if __name__ == '__main__':
    start_timestamp = int(time.time())
    print(f"Starting timestamp: {start_timestamp}. Start executing tests...")

    # Start executing tests
    execute_tests()

    # Start monitoring
    print("Test cases started. Start monitoring for finish testing...")
    PATH = "C:/Users/Laptop/Desktop/Achelos/IKEIPsecInspector1.7.0/workspace/logs/Test1/"
    COUNTER = 0
    SUCCESS = True
    while (not os.path.isfile(PATH + str(start_timestamp + COUNTER) + "Summary.html")):
        COUNTER += 1
        time.sleep(1)
        if COUNTER >= 1000: 
            SUCCESS = False
            break # Break if after 15 minutes nothing was found
    if not SUCCESS: exit("Testing was not successful. Exiting.")
    
    print(PATH + str(start_timestamp + COUNTER) + "Summary.html")
    print("Testcases Executed! Starting analysis...")

    # Start analysis of executed testcases
    print("Start analysis of test cases...")
    analyzer = Analyzer("C:/Users/Laptop/Desktop/Achelos/IKEIPsecInspector1.7.0/workspace/logs/Test1/")
    analyzer.analyze()
    print("Analysis executed. Report created. Exiting.")
    exit()
