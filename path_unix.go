//go:build !windows  
// +build !windows  
  
package main  
  
func getDefaultDBDir() string {  
    return "/tmp"  
}
