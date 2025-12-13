#!/usr/bin/env python3
devices = {
    'living_room_light': 0.06,
    'bedroom_light': 0.04,
    'kitchen_refrigerator': 1.2,
    'bathroom_heater': 2.0,
}

def filter(exp):
    blacklist = ['os', "'", '"']
    for char in blacklist:
        if char in exp:
            return False
    return True

def calculate():
    print("=" * 60)
    print("🏠 Smart Home Energy Calculator")
    print("=" * 60)
    print(f"Total devices: {len(devices)}")
    print(f"Daily consumption: {sum(devices.values()):.2f} kWh")
    print("=" * 60)
    print()
    print("Enter your energy calculation formula:")
    print()
    
    while True:
        expression = input(">>> ").strip()
        
        if not expression:
            continue
            
        if expression.lower() == 'exit':
            print("Goodbye! 👋")
            break
        
        if not filter(expression):
            print("❌ Security filter triggered! Blocked characters detected.")
            print()
            continue
        
        try:
            result = eval(expression, {'__builtins__': None})
            print(f"✅ Result: {result}")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        print()
    

if __name__ == "__main__":
    calculate()