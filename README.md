
# 🛡️ KQL Blue Team Hunting & Analysis Cheat Sheet

## 📌 Introduction
KQL (Kusto Query Language) is the language used to query databases on Microsoft platforms, including Azure Monitor, Azure Data Explorer, Microsoft Sentinel, Log Analytics, and Defender for Endpoint. It is an essential tool for those working in SOC, Blue Team, threat hunting, and incident response.

This document is a complete, comprehensive, and example-rich guide on using KQL for security activities.

---

## 🧰 Language Basics
| Command     | Description                                           |
| ----------- | ----------------------------------------------------- |
| `where`     | Filters rows based on a condition                     |
| `project`   | Selects only specific columns                         |
| `extend`    | Creates new calculated columns                        |
| `summarize` | Groups and aggregates (e.g., `count()`, `avg()`, `max()`) |
| `sort by`   | Sorts results                                        |
| `limit`     | Limits the number of rows (alias: `take`)             |
| `distinct`  | Returns only unique values                             |
| `top`       | Shows the top N sorted results                        |
| `render`    | Visualizes graphs (e.g., `render timechart`)          |
| `let`       | Defines variables or subqueries                       |

---

## 🕵️‍♂️ Filter and Comparison Operators
| Syntax                   | Description                               |
| ------------------------ | ----------------------------------------- |
| `==`, `!=`               | Equality / Inequality                     |
| `>`, `<`, `>=`, `<=`      | Numerical or temporal comparison         |
| `contains`, `!contains`   | Searches for substrings (case-insensitive)|
| `has`, `!has`             | Searches for entire words in text        |
| `startswith`, `endswith`  | Starts or ends with a string             |
| `in ("val1", "val2")`     | Belongs to one of the specified values   |
| `isnotempty()`, `isnull()`| Checks if the field has a value or is empty |

---

## 🕒 Time Management
| Command                | Description                                |
| ---------------------- | ------------------------------------------ |
| `now()`                | Current timestamp                          |
| `ago(1h)`, `ago(2d)`   | Delta relative to now (hours, days, minutes) |
| `datetime(2024-01-01)` | Static date                               |
| `bin(EventTime, 1h)`   | Rounds to time blocks of 1 hour           |

---

## 🧪 Advanced Hunting Commands
| Operator         | Description                                           |
| ----------------- | ----------------------------------------------------- |
| `parse`           | Extracts values from strings (e.g., raw log data)    |
| `extract()`       | Regex to parse data                                  |
| `mv-expand`       | Expands arrays or multi-value fields                 |
| `join kind=inner` | Joins tables (inner, leftouter, rightouter, etc.)     |
| `union`           | Unites multiple tables/sources                       |

---

## 📁 Common Tables in Microsoft Sentinel
| Table               | Main Content                                     |
| ------------------- | ------------------------------------------------ |
| `SecurityEvent`      | Windows security events (local logs)             |
| `SigninLogs`         | Azure AD sign-ins                                |
| `DeviceEvents`       | General endpoint events                          |
| `DeviceProcessEvents`| Process executions                               |
| `AlertEvidence`      | Evidence related to an alert                     |
| `CommonSecurityLog`  | Logs from security appliances (e.g., firewalls)  |

---

## 🔥 Practical Hunting Queries

### 1. Find Suspicious Processes (PowerShell)
```kql
SecurityEvent
| where EventID == 4688
| where CommandLine has "powershell"
| project TimeGenerated, Account, CommandLine, NewProcessName
```

### 2. Most Active IPs in Firewall Blocks
```kql
CommonSecurityLog
| where DeviceAction == "Blocked"
| summarize Count = count() by SourceIP
| sort by Count desc
```

### 3. Failed Logins per User
```kql
SigninLogs
| where ResultType == "50074"
| summarize FailedLogins = count() by UserPrincipalName
```

### 4. Failed Logins Over Time (Graph)
```kql
SigninLogs
| where ResultType == "50074"
| summarize Count = count() by bin(TimeGenerated, 1h)
| render timechart
```

### 5. Detect IOC (Suspicious IPs)
```kql
DeviceNetworkEvents
| where RemoteIP in ("185.53.88.21", "45.13.190.180")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteIP
```

### 6. Persistence via Recurring Executions (e.g., Run Key Registry)
```kql
DeviceRegistryEvents
| where RegistryKey contains "Run"
| where ActionType == "RegistryValueSet"
| project TimeGenerated, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

### 7. DNS Beaconing
```kql
DeviceNetworkEvents
| where RemotePort == 53
| summarize BeaconCount = count() by RemoteIP, bin(TimeGenerated, 1h)
| sort by BeaconCount desc
```

### 8. Custom Variable and Dynamic Usage
```kql
let targetIP = "180.125.30.4";
DeviceNetworkEvents
| where RemoteIP == targetIP
| project Timestamp, DeviceName, InitiatingProcessCommandLine, RemoteIP
```

### 9. Executions from Suspicious Folders (Temp, AppData)
```kql
DeviceProcessEvents
| where FolderPath has_any ("\Temp\", "\AppData\")
| project Timestamp, DeviceName, FileName, ProcessCommandLine
```

### 10. Export Data for Reporting
```kql
SigninLogs
| where TimeGenerated > ago(7d)
| summarize TotalLogins = count(), Failed = countif(ResultType != "0") by UserPrincipalName
```

---

## 💡 Operational Tips
* Use `let` to make complex queries more readable
* Always test queries on small datasets before scheduling them
* Join multiple tables with `join` for advanced correlation
* Use `render` to graph time-based patterns
* Automate hunting by saving queries in **workbooks** or **analytic rules**

---

## 📚 Extra Resources
* [Microsoft KQL Docs](https://docs.microsoft.com/en-us/azure/data-explorer/kusto/query/)
* [Microsoft Sentinel GitHub Hunting Queries](https://github.com/Azure/Azure-Sentinel/tree/master/Detections)
* [Interactive KQL Tutorial](https://aka.ms/lademo)
