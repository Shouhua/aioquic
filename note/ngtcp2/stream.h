#include "list.h"

struct _stream_data
{
	uint8_t *data;
	size_t data_size;
	struct list_head link;
};

struct _stream
{
	int64_t id;
	struct list_head buffer;
	size_t sent_offset;
	size_t acked_offset;

	struct list_head link; // 用于connection中的streams
};

typedef struct _stream stream;
typedef struct _stream_data stream_data;

stream stream_new(uint64_t stream_id);
void stream_free(stream *s);
int64_t stream_get_id(stream *s);
int stream_push_data(stream *s, const uint8_t *data, size_t data_size);
void stream_mark_sent(stream *s, size_t offset);
uint8_t *stream_peek_data(stream *s, size_t *data_size);

stream *stream_new(uint64_t stream_id)
{
	stream *s = (stream *)malloc(sizeof(stream));
	s->id = stream_id;
	init_list_head(&s->buffer);
	s->sent_offset = 0;
	s->acked_offset = 0;

	return s;
}

void stream_free(stream *s)
{
	if (!s)
		return;

	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &s->buffer)
	{
		stream_data *sd = list_entry(el, stream_data, link);
		if (sd->data)
			free(sd->data);
		list_del(el);
		free(sd);
	}
	free(s);
}

int64_t stream_get_id(stream *s)
{
	return s->id;
}

int stream_push_data(stream *s, const uint8_t *data, size_t data_size)
{
	stream_data *sd = (stream_data *)malloc(sizeof(stream_data));
	sd->data = data;
	sd->data_size = data_size;
	list_add_tail(stream_data, &s->buffer);
	return 0;
}

uint8_t *stream_peek_data(stream *s, size_t *data_size)
{
	size_t start_offset = s->sent_offset - s->acked_offset;
	size_t offset = 0;

	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &s->buffer)
	{
		stream_data *sd = list_entry(el, stream_data, link);
		if (start_offset - offset < sd->data_size)
		{
			data_size = sd->data_size - (start_offset - offset);
			return sd->data + (start_offset - offset);
		}
		offset += sd->data_size;
	}
	*data_size = 0;
	return NULL;
}

void stream_mark_sent(stream *s, size_t offset)
{
	s->sent_offset += offset;
}

void stream_mark_acked(stream *s, size_t offset)
{
	struct list_head *el, *el1;
	list_for_each_safe(el, el1, &s->buffer)
	{
		stream_data *sd = list_entry(el, stream_data, link);
		if (s->acked_offset + sd->data_size > offset)
			break;
		s->acked_offset += sd->data_size;
		list_del(el);
		free(el);
	}
}