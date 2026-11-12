#include <cstdint>

volatile uint32_t sink;

struct Base {
    virtual uint32_t compute(uint32_t x) { return x + 1; }
    virtual uint32_t transform(uint32_t x, uint32_t y) { return x * y; }
    virtual ~Base() {}
};

struct Derived : Base {
    uint32_t offset;
    Derived(uint32_t o) : offset(o) {}
    uint32_t compute(uint32_t x) override { return x + offset; }
    uint32_t transform(uint32_t x, uint32_t y) override { return (x + offset) * y; }
};

struct AnotherDerived : Base {
    uint32_t scale;
    AnotherDerived(uint32_t s) : scale(s) {}
    uint32_t compute(uint32_t x) override { return x * scale; }
    uint32_t transform(uint32_t x, uint32_t y) override { return x * scale + y; }
};

// Force vtable dispatch through pointer — compiler can't devirtualize
__attribute__((noinline))
uint32_t call_compute(Base *obj, uint32_t x) {
    return obj->compute(x);
}

__attribute__((noinline))
uint32_t call_transform(Base *obj, uint32_t x, uint32_t y) {
    return obj->transform(x, y);
}

// Multiple objects through same interface
__attribute__((noinline))
uint32_t polymorphic_sum(Base *a, Base *b, uint32_t x) {
    return a->compute(x) + b->compute(x) + a->transform(x, x);
}

// Array of base pointers — common vtable dispatch pattern
__attribute__((noinline))
uint32_t process_array(Base **arr, uint32_t count, uint32_t val) {
    uint32_t total = 0;
    for (uint32_t i = 0; i < count; i++) {
        total += arr[i]->compute(val);
        total += arr[i]->transform(val, i);
    }
    return total;
}

int main() {
    Base b;
    Derived d(10);
    AnotherDerived ad(3);

    sink = call_compute(&b, 5);
    sink = call_compute(&d, 5);
    sink = call_compute(&ad, 5);

    sink = call_transform(&b, 3, 4);
    sink = call_transform(&d, 3, 4);
    sink = call_transform(&ad, 3, 4);

    sink = polymorphic_sum(&b, &d, 7);
    sink = polymorphic_sum(&d, &ad, 7);

    Base *arr[3] = {&b, &d, &ad};
    sink = process_array(arr, 3, 42);

    return 0;
}
