//go:build windows  
// +build windows  
  
package main  
  
import (  
    "os"  
    "path/filepath"  
)  
  
func getDefaultDBDir() string {  
    exePath, err := filepath.Abs(os.Args[0])  
    if err != nil {  
        return "."  
    }  
    return filepath.Join(filepath.Dir(exePath), "ip_data")  
}
