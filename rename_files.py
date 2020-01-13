import os

# simple script to rename file in a directory
path = '/path/to/database/'
directory = 'directory/'

counter = 1

for file in os.listdir(path + directory):
    dst = "Subject - " + str(counter) + ".jpg"
    src = path + directory + file
    dst = path + directory + dst

    os.rename(src, dst)
    counter += 1

