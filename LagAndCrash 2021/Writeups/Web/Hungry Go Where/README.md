# Hungry Go Where?
---

### Challenge Description

My eyesight isn’t very good… can you help give me some food?

http://challenge2.lagncrash.com:23887/

---

### Solution

Opening the source code of the website, we find something interesting

```html
        <div>
            <a id="flag" style="display: none;" href="canyouseeme.txt" download>Here you go! I found this piece of paper but it looks kinda weird though...</a>
        </div>
```

There is a file called canyouseeme.txt. 

If you append /canyouseeme.txt to the end of the website you can view the file. However the text file is printed in a very weird syntax, which we cannot make anything out off.

```
â ¼â šâ ¼â â ¼â â ¼â šâ ¼â šâ ¼â šâ ¼â š â ¼â šâ ¼â â ¼â â ¼â šâ ¼â â ¼â â ¼â
```

After some time of struggling, I decided to see if curling the webpage will give us anything.

```
$ curl http://challenge2.lagncrash.com:23887/canyouseeme.txt
⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠁⠼⠁ ⠼⠚⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠁ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠚⠼⠚⠼⠚ ⠼⠚⠼⠁⠼⠁⠼⠚⠼⠁⠼⠚⠼⠚
```

This is braille!!

I immediately plugged this into cyberchef and I got this:

```
#J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#J#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#A#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#J#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#A #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#A#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#J#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#A #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#A #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#J#J #J#A#A#J#J#J#J #J#A#J#J#J#J#J #J#A#A#J#J#J#J #J#A#A#J#A#A#J #J#A#A#J#A#A#A #J#A#J#J#J#J#J #J#A#A#J#J#J#A #J#A#A#J#J#J#J #J#A#A#J#A#J#J
```

Trust me we tried everything we could, converting the characters to 1s and 0s to see if it supposed to be binary. It's not.

Something clearly went wrong with the conversion of the braille. I sent the whole chunk of braille to my teammates and we decided to see what we can do with it.

After a some time, we decided to try to convert the braille again but with another website.

Using dcode.fr and converting the braille, we got this:

```
0110000 0110110 0110100 0100000 0110001 0110000 0110011 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110100 0100000 0110001 0110000 0110101 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110100 0100000 0110000 0110110 0110011 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110111 0100000 0110001 0110000 0110010 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110111 0100000 0110000 0110110 0110100 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110100 0100000 0110000 0110111 0110000 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110110 0100000 0110000 0110110 0110001 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110110 0100000 0110001 0110000 0110101 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110100 0100000 0110001 0110000 0110010 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110111 0100000 0110000 0110110 0110011 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110101 0100000 0110001 0110000 0110110 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110110 0100000 0110000 0110110 0110110 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110011 0100000 0110000 0110110 0110000 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110111 0100000 0110000 0110110 0110010 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110101 0100000 0110001 0110000 0110110 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110111 0100000 0110000 0110110 0110100 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110100 0100000 0110000 0110111 0110000 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110110 0100000 0110000 0110110 0110101 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110101 0100000 0110001 0110000 0110110 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110110 0100000 0110000 0110110 0110110 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110011 0100000 0110000 0110110 0110000 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110011 0100000 0110000 0110110 0110000 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110110 0100000 0110000 0110110 0110100 0100000 0110000 0110100 0110000 0100000 0110000 0110110 0110111 0100000 0110001 0110000 0110100
```

That clearly looks like binary. Plugging the binary back into cyberchef, and changing the settings to 7 bytes, we get this:

```
064 103 040 064 105 040 064 063 040 067 102 040 067 064 040 064 070 040 066 061 040 066 105 040 064 102 040 067 063 040 065 106 040 066 066 040 063 060 040 067 062 040 065 106 040 067 064 040 064 070 040 066 065 040 065 106 040 066 066 040 063 060 040 063 060 040 066 064 040 067 104
```

Now that's octal. Converting the text from octal gives us some hex 

```
4C 4E 43 7B 74 48 61 6E 4B 73 5F 66 30 72 5F 74 48 65 5F 66 30 30 64 7D
```

Converting it from hex to ascii gives us the flag.

```
LNC{tHanKs_f0r_tHe_f00d}
```
