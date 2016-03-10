


CSVFileView v2.26
Copyright (c) 2011 - 2016 Nir Sofer
Web site: http://www.nirsoft.net



Description
===========

CSVFileView is a simple CSV file viewer/converter utility that allows you
to easily view the content of CSV or tab-delimited file created by
NirSoft utilities or by any other software, in a simple table viewer. You
can sort the lines according to one of the fields, remove unwanted fields
and change their order, and then save the result back into CSV file,
tab-delimited file, XML file, or HTML report.



Known Limitations
=================


* CSVFileView cannot load extremely large csv files.



Versions History
================


* Version 2.26:
  o Added 'New CSVFileView Instance' under the File menu, for opening
    a new window of CSVFileView.

* Version 2.25:
  o Fixed bug: CSVFileView displayed wrong items when opening a file
    with a filter turned on.
  o Fixed bug: CSVFileView failed to load properly a filter string
    from the .cfg file that had single quote in the first and last
    characters.
  o Fixed bug: 'Auto Size Columns' option was disabled immediately
    after loading a file.

* Version 2.22:
  o Reduced the memory footprint while loading UTF8 or Ascii file.

* Version 2.21:
  o The properties window is now resizable.
  o Added </tr> </td> closing tags to the HTML files.

* Version 2.20:
  o Added 'Display Filter' option (F2). The display filter is
    somewhat similar to the SQL WHERE clause, for example... The
    following filter will instruct CSVFileView to display only lines with
    'Yes' value in the Connected column and the 'Device Name' column
    contains a 'USB' string:
    Connected = 'Yes' AND 'Device Name' CONTAINS 'USB'
  o Added 'Load Filter' option to the 'Advanced Open' window. It's
    similar to the 'Display Filter' feature, but instead of filtering the
    file after it's already loaded , the load filter skip items during
    the loading process, so the file will be loaded faster and
    CSVFileView will consume less memory.
  o Added 'First line contains column names' and 'Automatically
    detect the delimiter and quotes characters' options to the 'Advanced
    Open' window.
  o Added /aload command-line option, for loading a file according to
    the 'Advanced Open' settings.
  o You can now specify any variable inside the CSVFileView.cfg file
    as a command-line parameter, for example... In order to turn off the
    'First Line Contains Column Names' option:
    CSVFileView.exe /FirstLineColumnNames 0

* Version 2.16:
  o CSVFileView now displays an error message in the status bar when
    it fails to open a file.

* Version 2.15:
  o Added option to save the text/xml/csv/html files in UTF-8
    (Options -> Unicode/Ascii Save Mode -> Always UTF-8 )

* Version 2.10:
  o Added 'Enable String Interning' option. When it's turned on,
    CSVFileView tries to detect repeating column values, and store them
    in memory only once, instead of multiple times. This option can be
    useful if you load a large file with many repeating strings, because
    the memory consumption of CSVFileView will decrease dramatically.
    However, the loading process will be slower than normal.
  o Fixed issue: When loading a large file, some actions, like
    selecting items and copying selected items to the clipboard were very
    slow.
  o When the 'After Loading File - Sort By' option is set to
    'Original File Order', the loading process will be faster. (In
    previous versions, CSVFileView called the sort function when it's not
    really needed...)
  o Added 64-bit version.

* Version 2.06:
  o Added /sort command-line option (For using with the save
    command-line options - /stab, /scomma, /shtml ...)

* Version 2.05:
  o Added option to export to JSON file.

* Version 2.02:
  o Added 'Add Byte Order Mark To Unicode Files' option. If you turn
    it off, CSVFileView won't add Byte Order Mark (BOM) when saving to
    Unicode file.

* Version 2.01:
  o Fixed bug: CSVFileView failed to remember the last size/position
    of the main window if it was not located in the primary monitor.

* Version 2.00:
  o Added new file type in 'Save Selected Items' option: Custom
    Delimited File. You can set the desired delimiter and quote
    characters of this file type using 'Custom Delimited File Settings'
    (Ctrl+F9)
  o Added 'Always On Top' option.

* Version 1.96:
  o Added secondary sorting support: You can now get a secondary
    sorting, by holding down the shift key while clicking the column
    header. Be aware that you only have to hold down the shift key when
    clicking the second/third/fourth column. To sort the first column you
    should not hold down the Shift key.

* Version 1.95:
  o Fixed to find the correct item when typing the string you want to
    search into the main List View. (This feature stopped working on
    version 1.85)

* Version 1.93:
  o Added 'Keep Columns Size/Order on Refresh' option.

* Version 1.92:
  o Added 'Clear Recent Files List' option.

* Version 1.91:
  o Added /cfg command-line option, which instructs CSVFileView to
    use a config file in another location instead if the default config
    file, for example:
    CSVFileView.exe /cfg "%AppData%\CSVFileView.cfg"

* Version 1.90:
  o Added 'Copy Sorted Column Data' option, which copies to the
    clipboard the text of all selected items, but only the column that is
    currently sorted.
  o Added 'Select All' and 'Deselect All' options in the 'Choose
    Columns' window.
  o CSVFileView now detects the date/time of Apache Web server log
    (For example: 29/Jul/2013:10:38:57 -0400)
  o Added option to specify space character ( /s ) as delimiter in
    the 'Advanced Open' window.

* Version 1.87:
  o Added 'Original File Order - Descending' and 'First Column -
    Descending' to the 'After Loading File - Sort By' option.

* Version 1.86:
  o While loading large files, CSVFileView now displays progress
    information in the status bar.

* Version 1.85:
  o CSVFileView now loads large files much faster and with less
    memory usage ( /FastMode command-line option is not needed anymore.
    If from some reason you want to run it in the previous mode, you can
    execute CSVFileView with /NoFastMode command-line option).

* Version 1.82:
  o Fixed bug: When 'Auto Refresh' option was turned on, trying to
    load a large csv file caused CSVFileView to hang and to consume
    extreme amount of memory.

* Version 1.81:
  o Added 'Beep On New Line' option. (Works only on partial refresh)

* Version 1.80:
  o When selecting a single line, the line number in the original
    file is now displayed in the status bar (Be aware that empty lines
    are not counted by CSVFileView)
  o Added option to display the csv lines with different font
    (Options -> Select Another Font).

* Version 1.76:
  o Added 'Scroll To Bottom On New Line' option. If this option is
    turned on, a parial refresh is made, and new lines were added since
    the last refresh, then the List-View is scrolled to the bottom in
    order to show you the added new lines.

* Version 1.75:
  o Added 'Partial Refresh' option (Ctrl+F5), which makes a smooth
    refresh, without reloading the entire table. However, Partial Refresh
    will not work properly if you add/remove columns or change their
    position.
  o Added 'Auto Refresh Mode' which allows you to choose how to
    refresh when the 'Auto Refresh' option is turned on - Partial Refresh
    or Full refresh.

* Version 1.71:
  o Fixed bug: CSVFileView crashed when opening a file with large
    amount of columns.

* Version 1.70:
  o The properties window now supports multiple pages, for handling
    files with large amount of columns.

* Version 1.67:
  o Fixed bug: When opening a file with /load command-line option,
    CSVFileView sorted the list by the first column, even if the 'Sort by
    original file order' option was selected.

* Version 1.66:
  o Added 'Load only from line number...' option (In 'Advanced Open'
    window)
  o Fixed issue: The properties and the other windows opened in the
    wrong monitor, on multi-monitors system.

* Version 1.65:
  o Added option to load last xx lines or first xx lines from the
    file. (In 'Advanced Open' window)
  o Fixed issue: If you open a file with 'Advanced Open' window and
    then do a refresh (F5) CSVFileView now loads the file with the last
    'Advanced Open' settings. In previous versions, it opened the file
    with the default settings.

* Version 1.60:
  o Added 'Open Text In Clipboard' option (Ctrl+F7), which allows you
    to open csv/tab-delimited text that you copied to the clipboard.
  o You can also specify 'Clipboard:' as a filename in the 'Advanced
    Open' window or from command-line (/Load Clipboard:) , in order to
    grab the csv/tab-delimited text from the clipboard.
  o The 'Automatic Date Sorting' feature now also works with
    combination of date and time, for example: 22/03/2011 21:34:25

* Version 1.55:
  o Added 'After Loading File - Sort By' option, which allows you to
    choose how to sort the file after loading it into CSVFileView - by
    original file order or by the first column.
  o Added 'Automatic Column Size' option, which allows you to choose
    how to set the columns size after loading a file - Fixed Size
    (Default), By Column Values Only, or By Column Values+Headers.
  o You can now load a file from stdin, by specifying stdin: as a
    filename, for example:
    CSVFileView.exe /Load stdin: < c:\temp\myfile.csv

* Version 1.51:
  o Added 'Auto Size Columns+Headers' option, which allows you to
    automatically resize the columns according to the row values and
    column headers.

* Version 1.50:
  o Added 'Open Recent File' menu (Under the File menu), which allows
    you to easily open the last 10 csv files that you have previously
    opened.

* Version 1.45:
  o Added new mode that allows you to load large .csv files much
    faster and with less memory usage. This mode is currently in Beta, so
    in order to activate it, you have to run CSVFileView with /FastMode
    command-line option:
    CSVFileView.exe /FastMode
    If you use CSVFileView for loading large files, it's highly
    recommended that you try this mode and report about any bug/problem
    you discover.

* Version 1.40:
  o Added 'Hide Selected Lines' option (Ctrl+H)

* Version 1.35:
  o Added 'Advanced Open' option, which allows you to specify the
    delimiter and quotes characters of the file you want to load. This
    option is useful for files that their delimiter character is not
    detected correctly by CSVFileView.

* Version 1.30:
  o Added 'Allow MultiLine Fields' option. When it's turned on,
    CSVFileView will be able to load csv file containing field values
    with multiple lines.
  o Added option to stop the loading process of csv file, by clicking
    the 'Stop' menu item, or by pressing the Esc key.

* Version 1.25:
  o Added 'Auto Refresh' option. When it's turned on, CSVFileView
    automatically reloads the file when a change in the size/modified
    time of the file is detected.
  o Added 'Descending Sort By Original Order' option (Ctrl+F8)
  o When using the refresh option (F5), the lines are now sorted
    according to the last sorting you chose (by clicking the column
    headers).

* Version 1.20:
  o Added 'Unicode/Ascii Default Open Mode' option, which instructs
    CSVFileView how to open a file without a Unicode signature (byte
    order mark) - as Ascii (the default), as Unicode, or as UTF8.

* Version 1.15:
  o Added 'Automatic Date Sorting' option. Be aware that date sorting
    doesn't work with all date formats.

* Version 1.12:
  o Fixed the problem with negative numbers sorting.

* Version 1.11:
  o Fixed bug: CSVFileView didn't display all columns if the first
    line had one or more empty fields.

* Version 1.10:
  o Added /load command-line option, which allows you to specify the
    file to open from command-line.
  o Added support for save command-line options (/shtml , /sxml, and
    so on), which can be used together with /load command-line option for
    converting the csv file into xml/html/tab-delimited file.
  o Added 'Explorer Context Menu' option. When this option is
    enabled, 'Open With CSVFileView' menu item is added when you right
    click on a text file.
  o Automatic delimiter detection - When CSVFileView cannot find a
    comma or tab character in the first line, it tries to automatically
    detect the right delimiter character and parse the file with it.
  o Added support for loading UTF8 files.

* Version 1.00 - First release.



Using CSVFileView
=================

CSVFileView doesn't require any installation process or additional dll
files. In order to start using it, simply run the executable file -
CSVFileView.exe
After running CSVFileView, you can open the desired CSV/Tab-Delimited
file by using the 'Open CSV\Tab-Delimited File' option (Ctrl+O) or by
dragging the file from Explorer into the main window of CSVFileView.
If the first line of the CSV/Tab-Delimited file doesn't contain the
column names, you should turn off the 'First Line Contains Column Names'
option (Under the Options menu) before opening the file.

After opening the desired file, you can do the following actions:
* Sort the lines by one of the fields, simply by clicking the right
  column header. If the column values are numeric, CSVFileView
  automatically makes a numeric sorting instead of string sorting.
* Remove one or more columns or change their position by using the
  'Choose Columns' window (F7). You can also change the position of the
  columns by dragging the column headers into another position.
* Select one or more lines, or select all lines (Ctrl+A), and then
  saving them into csv, comma-delimited, XML, or HTML file, by using the
  'Save Selected Items' option (Ctrl+S). You can also press Ctrl+C to
  copy the selected lines into the clipboard, and then paste them into
  Excel.



More Options
============


* Unicode/Ascii Save Mode: By default, CSVFileView saves all files in
  Unicode, except of csv file, which is saved as Ascii. The reason for
  saving csv files as Ascii is... Microsoft Excel. That's because
  Microsoft Excel doesn't open properly csv files that are saved as
  Unicode.
  You can change the default behavior, by going to Options ->
  Unicode/Ascii Save Mode, and then choosing the desired save mode -
  Ascii or Unicode.
* Add Header Line To CSV/Tab-Delimited File: When this option is turned
  on, and you export the selected lines into csv/tab-delimited file, the
  first added line contains the column/field names.
* First Line Contains Column Names: When this option is turned on,
  CSVFileView uses the first line of the opened csv/tab-delimited file as
  the column names list.
* Automatic Numeric Sorting: When this option is turned on, CSVFileView
  automatically uses numeric sorting when numeric values are detected.



Using Filters
=============

Starting from version 2.20, CSVFileView allows you to apply a filter for
viewing only the lines you need.
There are 2 places that you can use filter:
* Display Filter window (F2): The Filter is applied after the entire
  file is already loaded. When using this option, you can easily remove
  the filter and view again all items by switching the 'Use Display
  Filter' option (Ctrl+F2) or you can press F2 again and use another
  filter.
* 'Advanced Open' window (Load Filter): The filter is applied while
  loading the file, so all lines that are filtered out by your filter are
  not loaded at all. If you filter out a lot of lines with the load
  filter, then the file will be loaded much faster and CSVFileView will
  consume less memory.

A filter string of CSVFileView is somewhat similar to the SQL WHERE
clause. CSVFileView currently supports the following operators:
=   !=   >   <   >=   <=   LIKE CONTAINS BEGINSWITH ENDSWITH NOT AND OR

Here's some examples and rules for using the CSVFileView filters:
* The following filter instructs CSVFileView to display only items with
  'Yes' in 'Connected' column and 'No' in 'Disabled' column:
  Connected = 'Yes' And Disabled = 'No'
* Display only items with value different than 'Yes' in 'Connected'
  column and with 'SerialNumber' column begins with '12' string:
  Connected != 'Yes' And SerialNumber BEGINSWITH '12'
* Display only items the their Filename column begins with 'f' and has
  more 7 characters (You can use ? and * in LIKE operator, like the
  wildcard of Windows):
  Filename LIKE 'f???????'
* Display only items the their Filename column contains 'abc' string or
  'qwe' string.
  Filename CONTAINS 'abc' OR Filename CONTAINS 'qwe'
* When a column name has a space character, you must put it in quotes,
  for example:
  'Device Name' CONTAINS 'USB'
* When there are no column names, you can use 'Column1' as the first
  column, 'Column2' for the second column, and so on... For example:
  Column1 LIKE '??34*' and Column4 = 'Yes'
* You can use the NOT operator to reverse the result, for example...
  This filter will display items that don't contain 'txt' string in the
  Filename column:
  Filename NOT CONTAINS 'txt'
* You can use the   >   <   >=   <=   operators with numeric values in
  order to filter by a range of numbers. For example, in order to display
  only records with ID value between 100 and 200:
  ID >= 100 and ID <= 200
* When mixing and/or in the same filter, you must use parentheses, for
  example:
  (Column1 = '3' AND Column4 = 'No') OR (Column1 = '4' AND Column4 =
  'Yes')

You can also apply a load filter from command-line by using /aload with
other command-line options to set the 'Advanced Open' settings, for
example:
CSVFileView.exe /AutoDetectChars 1 /UseLoadFilter 1 /LoadFilterStr
"Column1 LIKE 'a*' " /aload C:\temp\myfile.csv
CSVFileView.exe /AutoDetectChars 1 /UseLoadFilter 1 /LoadFilterStr
"Column1 = 'Yes' and Column2 = 'No' " /aload C:\temp\myfile.csv /scomma
c:\temp\filtered_file.csv



Opening Web Server Log File
===========================

With CSVFileView, you can also open a log file of Apache or other Web
server that generates a log file in the same format. In order to do that,
you should turn off the 'First Line Contains Column Names' option, open
the 'Advanced Open' window (Ctrl+Shirt+O), type \s (space character) in
the delimiter field, and "[] in the quotes field. Choose the log file to
open and then press Ok.



Command-Line Options
====================



/load <Filename>
Start CSVFileView with the specified csv/tab-delimited file.

/aload <Filename>
Start CSVFileView with the specified csv/tab-delimited file. The file
will be loaded according to the 'Advanced Open' settings.

/cfg <Filename>
Start CSVFileView with the specified configuration file. For example:
CSVFileView.exe /cfg "c:\config\csv.cfg"
CSVFileView.exe /cfg "%AppData%\CSVFileView.cfg"

/stext <Filename>
Save the loaded csv/tab-delimited file into a regular text file.

/stab <Filename>
Save the loaded csv/tab-delimited file into a tab-delimited text file.

/scomma <Filename>
Save the loaded csv/tab-delimited file into a comma-delimited text file
(csv).

/stabular <Filename>
Save the loaded csv/tab-delimited file into a tabular text file.

/shtml <Filename>
Save the loaded csv/tab-delimited file into HTML file (Horizontal).

/sverhtml <Filename>
Save the loaded csv/tab-delimited file into HTML file (Vertical).

/sxml <Filename>
Save the loaded csv/tab-delimited file into XML file.

/scustom <Filename>
Save the loaded csv/tab-delimited file into a custom delimited text file.

/sjson <Filename>
Save the loaded csv/tab-delimited file into a JSON file.

/sort <column>
This command-line option can be used with other save options for sorting
by the desired column. The <column> parameter can specify the column
index (0 for the first column, 1 for the second column, and so on) or the
name of the column, like "Description" and "User Name". You can specify
the '~' prefix character (e.g: "~Description") if you want to sort in
descending order. You can put multiple /sort in the command-line if you
want to sort by multiple columns.

Examples:
CSVFileView.exe /Load "c:\temp\1.csv" /shtml "c:\temp\1.html" /sort 2
/sort ~1
CSVFileView.exe /Load "c:\temp\1.csv" /shtml "c:\temp\1.html" /sort
"~Value" /sort "Description"

In addition to the above command-line options, you can also specify any
variable inside the CSVFileView.cfg file as a command-line parameter, for
example... In order to turn off the 'First Line Contains Column Names'
option:
CSVFileView.exe /FirstLineColumnNames 0



Translating CSVFileView to other languages
==========================================

In order to translate CSVFileView to other language, follow the
instructions below:
1. Run CSVFileView with /savelangfile parameter:
   CSVFileView.exe /savelangfile
   A file named CSVFileView_lng.ini will be created in the folder of
   CSVFileView utility.
2. Open the created language file in Notepad or in any other text
   editor.
3. Translate all string entries to the desired language. Optionally,
   you can also add your name and/or a link to your Web site.
   (TranslatorName and TranslatorURL values) If you add this information,
   it'll be used in the 'About' window.
4. After you finish the translation, Run CSVFileView, and all
   translated strings will be loaded from the language file.
   If you want to run CSVFileView without the translation, simply rename
   the language file, or move it to another folder.



License
=======

This utility is released as freeware. You are allowed to freely
distribute this utility via floppy disk, CD-ROM, Internet, or in any
other way, as long as you don't charge anything for this and you don't
sell it or distribute it as a part of commercial product. If you
distribute this utility, you must include all files in the distribution
package, without any modification !



Disclaimer
==========

The software is provided "AS IS" without any warranty, either expressed
or implied, including, but not limited to, the implied warranties of
merchantability and fitness for a particular purpose. The author will not
be liable for any special, incidental, consequential or indirect damages
due to loss of data or any other reason.



Feedback
========

If you have any problem, suggestion, comment, or you found a bug in my
utility, you can send a message to nirsofer@yahoo.com
