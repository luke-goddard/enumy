#ifndef VECTOR_H
#define VECTOR_H

#define VECTOR_INIT_CAPACITY 4

#define VECTOR_INIT(vec) \
    vector vec;          \
    vector_init(&vec)
#define VECTOR_ADD(vec, item) vector_add(&vec, (void *)item)
#define VECTOR_SET(vec, id, item) vector_set(&vec, id, (void *)item)
#define VECTOR_GET(vec, type, id) (type) vector_get(&vec, id)
#define VECTOR_DELETE(vec, id) vector_delete(&vec, id)
#define VECTOR_TOTAL(vec) vector_total(&vec)
#define VECTOR_FREE(vec) vector_free(&vec)

typedef struct Vector
{
    void **items;
    int capacity;
    int total;
} Vector;

void vector_init(Vector *);
int vector_total(Vector *);
void vector_add(Vector *, void *);
void vector_set(Vector *, int, void *);
void *vector_get(Vector *, int);
void vector_delete(Vector *, int);
void vector_free(Vector *);

#endif